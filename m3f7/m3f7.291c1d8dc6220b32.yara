
rule m3f7_291c1d8dc6220b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.291c1d8dc6220b32"
     cluster="m3f7.291c1d8dc6220b32"
     cluster_size="9"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="faceliker cryxos html"
     md5_hashes="['0d514527eafb67da702cffa075771f43','1d20a36bfa87971ac323c53c59baab14','de017bfd3d6a14264dd6bbe1fd4e3a4d']"

   strings:
      $hex_string = { 783b6261636b67726f756e643a75726c28687474703a2f2f312e62702e626c6f6773706f742e636f6d2f2d425367354e484c4d4f44512f55594d4f505032524f }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
