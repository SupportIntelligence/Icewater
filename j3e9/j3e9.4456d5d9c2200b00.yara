
rule j3e9_4456d5d9c2200b00
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3e9.4456d5d9c2200b00"
     cluster="j3e9.4456d5d9c2200b00"
     cluster_size="200"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="madangel madang small"
     md5_hashes="['02cb696aa00d1b6865700f1c31c457a0','03cd6e973fb9e3352234547cfffc52e6','22c654370766c67eac5f7ce470ac726f']"

   strings:
      $hex_string = { 66813e4d5a78037901eb75ee0fb77e3c03fe8b6f7803ee8b5d2003de33c08bd683c304408b3b03fae80f00000047657450726f6341646472657373005e33c9b1 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
