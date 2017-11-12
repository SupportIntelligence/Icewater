
rule k3e9_03aca614ca9ad135
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.03aca614ca9ad135"
     cluster="k3e9.03aca614ca9ad135"
     cluster_size="4"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="qukart bbba berbew"
     md5_hashes="['5f45c9c8d4348f8c0376bd2f62ce4ea8','82a6cf8ed5a5a42fe8e20e0162615095','d84b7a943e1efa2262cc8c8c3aa965dc']"

   strings:
      $hex_string = { 636573734100000000930257616974466f7253696e676c654f626a65637400000097025769646543686172546f4d756c746942797465000000980257696e4578 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
