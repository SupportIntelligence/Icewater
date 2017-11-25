
rule k2377_4b123b4dc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2377.4b123b4dc6220b12"
     cluster="k2377.4b123b4dc6220b12"
     cluster_size="51"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="script exploit alescurf"
     md5_hashes="['00d63c8ef861439145d27ec564bedc0f','1c7f4e8530ffc3157c4b610b0ced5120','5a625b48a32ae8e57389067b2cd9f227']"

   strings:
      $hex_string = { 756e6374696f6e206e3833393733287335353136663232297b766172206336626538613d537472696e673b743266313064362b3d6336626538615b22665c7837 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
