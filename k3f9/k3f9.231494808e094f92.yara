
rule k3f9_231494808e094f92
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f9.231494808e094f92"
     cluster="k3f9.231494808e094f92"
     cluster_size="3724"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="bdmj memscan flooder"
     md5_hashes="['000eee08b5a185fd83fcb691cf1058f9','0025d9a5c0e3540584dfae1ef7592297','01284077b198a5baa62c134756e4584f']"

   strings:
      $hex_string = { 7bb63930bc1fa91f8389951fcc8a45c7d5c3c957306f2ad409141c9afaf1eec6a1c3bf3b6410ab085e308a0a2e92e2200ee8efb9f10e307f7d4a3fe4cb7da84a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
