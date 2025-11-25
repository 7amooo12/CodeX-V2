// Type declarations for jspdf-autotable
import { jsPDF } from 'jspdf';

declare module 'jspdf-autotable' {
  interface CellDef {
    content?: string | number;
    colSpan?: number;
    rowSpan?: number;
    styles?: Partial<Styles>;
  }

  interface ColumnDef {
    header?: string;
    dataKey?: string;
    width?: number;
  }

  interface Styles {
    font?: string;
    fontStyle?: 'normal' | 'bold' | 'italic' | 'bolditalic';
    fontSize?: number;
    cellPadding?: number | { top?: number; right?: number; bottom?: number; left?: number };
    lineColor?: number | [number, number, number];
    lineWidth?: number;
    fillColor?: number | [number, number, number] | false;
    textColor?: number | [number, number, number];
    halign?: 'left' | 'center' | 'right' | 'justify';
    valign?: 'top' | 'middle' | 'bottom';
    cellWidth?: 'auto' | 'wrap' | number;
    minCellWidth?: number;
    minCellHeight?: number;
    overflow?: 'linebreak' | 'ellipsize' | 'visible' | 'hidden';
  }

  interface UserOptions {
    includeHiddenHtml?: boolean;
    useCss?: boolean;
    theme?: 'striped' | 'grid' | 'plain';
    startY?: number | false;
    margin?: number | { top?: number; right?: number; bottom?: number; left?: number };
    pageBreak?: 'auto' | 'avoid' | 'always';
    rowPageBreak?: 'auto' | 'avoid';
    tableWidth?: 'auto' | 'wrap' | number;
    showHead?: 'everyPage' | 'firstPage' | 'never';
    showFoot?: 'everyPage' | 'lastPage' | 'never';
    tableLineColor?: number | [number, number, number];
    tableLineWidth?: number;
    
    head?: (string | CellDef)[][];
    body?: (string | number | CellDef)[][];
    foot?: (string | CellDef)[][];
    
    columns?: ColumnDef[];
    
    styles?: Partial<Styles>;
    headStyles?: Partial<Styles>;
    bodyStyles?: Partial<Styles>;
    footStyles?: Partial<Styles>;
    alternateRowStyles?: Partial<Styles>;
    columnStyles?: { [key: string]: Partial<Styles> };
    
    didDrawCell?: (data: CellHookData) => void;
    didDrawPage?: (data: HookData) => void;
    didParseCell?: (data: CellHookData) => void;
    willDrawCell?: (data: CellHookData) => void;
    willDrawPage?: (data: HookData) => void;
  }

  interface HookData {
    table?: Table;
    pageNumber?: number;
    settings?: UserOptions;
    doc?: jsPDF;
    cursor?: { x: number; y: number };
  }

  interface CellHookData extends HookData {
    cell?: Cell;
    row?: Row;
    column?: Column;
    section?: 'head' | 'body' | 'foot';
  }

  interface Table {
    finalY?: number;
    pageNumber?: number;
    pageCount?: number;
    settings?: UserOptions;
    columns?: Column[];
    head?: Row[];
    body?: Row[];
    foot?: Row[];
  }

  interface Cell {
    raw?: string | number;
    content?: string;
    styles?: Partial<Styles>;
    section?: 'head' | 'body' | 'foot';
    x?: number;
    y?: number;
    width?: number;
    height?: number;
    textPos?: { x: number; y: number };
  }

  interface Row {
    raw?: any;
    index?: number;
    section?: 'head' | 'body' | 'foot';
    cells?: { [key: string]: Cell };
    height?: number;
    maxCellHeight?: number;
  }

  interface Column {
    dataKey?: string | number;
    index?: number;
    width?: number;
  }

  function autoTable(doc: jsPDF, options: UserOptions): jsPDF;
  
  export default autoTable;
}

declare module 'jspdf' {
  interface jsPDF {
    lastAutoTable?: {
      finalY: number;
      pageNumber: number;
      pageCount: number;
    };
    previousAutoTable?: {
      finalY: number;
      pageNumber: number;
      pageCount: number;
    };
  }
}



