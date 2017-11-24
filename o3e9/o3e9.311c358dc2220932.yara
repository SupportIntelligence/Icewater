
rule o3e9_311c358dc2220932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.311c358dc2220932"
     cluster="o3e9.311c358dc2220932"
     cluster_size="530"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vbkrypt razy eyestye"
     md5_hashes="['0004309e6dd2c46a3f64f630b6648d60','00204b836494f0e0448b0d1dcdf5d53b','1252aa5cc97ef3213cd60052f48d1bf9']"

   strings:
      $hex_string = { 89539cdd97bb8ffd160de64cba6f2d4b9a95a4afbcfd0920be86ffff6becfad6a971d837543fa1ec16924f9c9b1995b430fe09201ea1ffffe5cd8649b18bc75f }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
