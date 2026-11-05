import { act, cleanup, renderHook } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { useAction } from "./hooks";
afterEach(cleanup);
it("rejects same-tick double submission before React renders disabled state", async () => {
  let finish!: (v: number) => void;
  const operation = vi.fn(
    () =>
      new Promise<number>((resolve) => {
        finish = resolve;
      }),
  );
  const { result } = renderHook(useAction);
  let first!: Promise<number | undefined>;
  await act(async () => {
    first = result.current.run(operation);
    expect(await result.current.run(operation)).toBeUndefined();
  });
  expect(operation).toHaveBeenCalledOnce();
  expect(result.current.busy).toBe(true);
  await act(async () => {
    finish(7);
    expect(await first).toBe(7);
  });
  expect(result.current.busy).toBe(false);
});
it("retains safe error state and permits an intentional retry", async () => {
  const { result } = renderHook(useAction);
  await act(async () => {
    await result.current.run(async () => {
      throw new Error("fault");
    });
  });
  expect(result.current.error).toBeInstanceOf(Error);
  await act(async () => {
    expect(await result.current.run(async () => 1)).toBe(1);
  });
  expect(result.current.error).toBeNull();
});
