import { afterEach, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { tamperProof, TreeDiagram } from "./Integrity";
import type { ProofView, TreeView } from "../../lib/contracts";
afterEach(cleanup);
const proof: ProofView = {
  profile_id: "test",
  spec_version: 1,
  tree_size: 3,
  chunk: { index: 0, length: 1024, sha256: "a".repeat(64) },
  siblings: ["b".repeat(64), "c".repeat(64)],
};
it("changes a copy without modifying the stored proof or trusted manifest", () => {
  const modified = tamperProof(proof);
  expect(modified.siblings[0]).not.toBe(proof.siblings[0]);
  expect(proof.siblings[0]).toBe("b".repeat(64));
  expect(modified.chunk).toEqual(proof.chunk);
});
it("changes the descriptor for a one-leaf proof", () => {
  const one = { ...proof, tree_size: 1, siblings: [] };
  expect(tamperProof(one).chunk.sha256).not.toBe(one.chunk.sha256);
  expect(one.chunk.sha256).toBe("a".repeat(64));
});
it("renders server-provided uneven topology and exposes keyboard-operable leaf selection", () => {
  const node = (
    id: string,
    start: number,
    count: number,
    left: string | null = null,
    right: string | null = null,
  ) => ({
    id,
    start,
    count,
    left,
    right,
    digest: "d".repeat(64),
    selected_path: start === 0,
    sibling: start !== 0,
  });
  const tree = {
    manifest: { chunk_count: 3 },
    selected_index: 0,
    mode: "full",
    nodes: [
      node("0:1", 0, 1),
      node("1:1", 1, 1),
      node("0:2", 0, 2, "0:1", "1:1"),
      node("2:1", 2, 1),
      node("0:3", 0, 3, "0:2", "2:1"),
    ],
  } as TreeView;
  const select = vi.fn();
  const { container } = render(<TreeDiagram tree={tree} select={select} />);
  expect(container.querySelectorAll("g.tree-node")).toHaveLength(5);
  expect(container.querySelectorAll("path")).toHaveLength(4);
  fireEvent.click(screen.getByRole("button", { name: "Chunk 2" }));
  expect(select).toHaveBeenCalledWith(2);
  expect(screen.getByRole("img").getAttribute("aria-label")).toContain(
    "3-leaf",
  );
});
it("has an explicit empty tree state", () => {
  render(
    <TreeDiagram
      tree={{ nodes: [] } as unknown as TreeView}
      select={() => {}}
    />,
  );
  expect(screen.getByRole("heading", { name: "Empty tree" })).toBeTruthy();
});
