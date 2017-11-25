
rule m3e9_0d0b1698939c4b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.0d0b1698939c4b16"
     cluster="m3e9.0d0b1698939c4b16"
     cluster_size="12998"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="delf delphi gate"
     md5_hashes="['0011ff8b89493c4e7dd71585b6347bf6','001854308f47c72efe2c8b37963f0cb3','00b26bb0c7f6078147bd569e97a48757']"

   strings:
      $hex_string = { 373531342e2053657475702076657273696f6e2031322e302e373630302e31363338352e5d0d0a436865636b696e6720666f7220506c61796c697374204f6266 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
