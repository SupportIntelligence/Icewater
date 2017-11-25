
rule m2377_691c0ad0d3a30932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2377.691c0ad0d3a30932"
     cluster="m2377.691c0ad0d3a30932"
     cluster_size="4"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="faceliker cryxos html"
     md5_hashes="['00303c4ebaace74c622574fea584da4d','176f7b987f173a622c0a87f1dffec045','e20509765363c033ebe5a2e6983ef958']"

   strings:
      $hex_string = { 3230706825453125424225413563273e4cc3a06d20c3a16f20c491e1bb936e67207068e1bba5633c2f613e0a3c7370616e206469723d276c7472273e2831293c }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
