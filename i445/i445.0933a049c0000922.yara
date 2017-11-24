
rule i445_0933a049c0000922
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i445.0933a049c0000922"
     cluster="i445.0933a049c0000922"
     cluster_size="5"
     filetype = "application/octet-stream"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vbsworm winlnk jenxcus"
     md5_hashes="['030c51e2f4fd37d9b1cd88a10369d265','28965d30d91169430fc7e74bc018ec18','e4e62c0ed11ab31df750ed42f99fa862']"

   strings:
      $hex_string = { 00260063006c00730026007300740061007200740020004d006900630072006f0073006f006600740022002000220045007800630065006c002e005700730046 }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
