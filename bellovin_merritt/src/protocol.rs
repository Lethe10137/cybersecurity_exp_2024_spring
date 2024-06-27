use std::{borrow::BorrowMut, fs::read, rc::Rc};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub async fn write_message(
    message_id: u32,
    fields: &Vec<&[u8]>,
    mut writer: Box<impl AsyncWriteExt + Unpin>,
) -> Result<(), Box<dyn std::error::Error>> {
    writer.write_u32_le(message_id).await?;
    writer.write_u32_le(fields.len() as u32).await?;

    for field in fields {
        writer.write_u32_le(field.len() as u32).await?;
        writer.write_all(*&field).await?;
    }
    Ok(())
}

pub async fn read_message(
    mut reader: Box<impl AsyncReadExt + Unpin>,
) -> Result<(u32, Vec<Vec<u8>>), Box<dyn std::error::Error>> {
    let mut result: Vec<Vec<u8>> = vec![];

    let message_id_read = reader.read_u32_le().await?;
    let field_cnt = reader.read_u32_le().await?;

    for _ in 0..field_cnt {
        let field_len = reader.read_u32_le().await?;
        let mut field = Vec::with_capacity(field_len as usize);
        field.resize(field_len as usize, 0);
        reader.read_exact(field.as_mut_slice()).await?;
        result.push(field);
    }

    Ok((message_id_read, result))
}
