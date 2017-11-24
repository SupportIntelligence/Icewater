
rule m3e9_291c94b9c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.291c94b9c2200b12"
     cluster="m3e9.291c94b9c2200b12"
     cluster_size="8"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="qvod viking jadtre"
     md5_hashes="['0b3de45393636e1447a14dec02495c07','45307e2daa994748f89424e29bc0201b','f021d66b4df2c3cdec17a844914e3add']"

   strings:
      $hex_string = { 6eab645e97d5b541ca562ed9e8ccc5cf17986de63ac7932d3fdb69b06fb4892b555b7662b8652746575afa32d138264ed3354c07348800e3b19458742a2acee7 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
