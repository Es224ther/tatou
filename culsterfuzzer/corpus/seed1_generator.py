from fpdf import FPDF

# Create a blank PDF
pdf = FPDF()
pdf.add_page()

# Save it as seed1.pdf
pdf.output("seed1.pdf")
