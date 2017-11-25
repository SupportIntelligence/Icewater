
rule n3f4_23991ec1c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f4.23991ec1c8000b12"
     cluster="n3f4.23991ec1c8000b12"
     cluster_size="4"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="johnnie malicious kryptik"
     md5_hashes="['4e1d5b0b82bb3344e9822ee57a697b9a','617c854f18fe06e43cccc9bcb83fbfcf','911aa94bf9fc452521a16a2b00c29633']"

   strings:
      $hex_string = { 57696e646f7773c2a0382e31202d2d3e0d0a2020202020203c212d2d3c737570706f727465644f532049643d227b31663637366337362d383065312d34323339 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
