
rule j3fd_305ca1a0c2000b14
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3fd.305ca1a0c2000b14"
     cluster="j3fd.305ca1a0c2000b14"
     cluster_size="27"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="toolbar webtoolbar downtango"
     md5_hashes="['19029bac3a2c44dc43d825233483235e','212657ff442e892192a70b25753637e7','ca863306bc569f917d6c1dc1cbb717e1']"

   strings:
      $hex_string = { 5c5fda3ef30f0a093522dbdbc03f00f9e60d5d67d1fda01e032bd940f7becc87665480a6a3b8f51962d5d226b19826ee9acb44a7455a8195151af55130820493 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
