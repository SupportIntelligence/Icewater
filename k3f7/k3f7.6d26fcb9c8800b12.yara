
rule k3f7_6d26fcb9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f7.6d26fcb9c8800b12"
     cluster="k3f7.6d26fcb9c8800b12"
     cluster_size="3"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="hidelink html script"
     md5_hashes="['3bcc90dcb95377e4e784b945c8ff8b54','5d76346c920ab2eba5b26cfbcb6374ae','c4c7680474319bfa1b25fdb43348b5e5']"

   strings:
      $hex_string = { bb2fd184d0b0d0bad1813a283334313229203c2f7370616e3e3c7374726f6e67207374796c653d226c696e652d6865696768743a20312e33656d3b223e393038 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
