import qrcode from "qrcode-generator";

export function qrMatrix(value) {
  if (typeof value !== "string" || value.length === 0) throw new Error("QR value must be a non-empty string");
  const code = qrcode(0, "M");
  code.addData(value, "Byte");
  code.make();
  const size = code.getModuleCount();
  const modules = Array.from({ length: size }, (_, row) =>
    Array.from({ length: size }, (_, column) => code.isDark(row, column)));
  return { size, modules };
}
