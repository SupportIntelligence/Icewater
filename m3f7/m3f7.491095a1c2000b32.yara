
rule m3f7_491095a1c2000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.491095a1c2000b32"
     cluster="m3f7.491095a1c2000b32"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="script faceliker html"
     md5_hashes="['3e68488cba3e21f9f10feab5e895b00c','5405312d7628f3a08e66dee1a7f403da','a78c249e65cdafb1456491b7db24044d']"

   strings:
      $hex_string = { 3d5b224142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768696a6b6c6d6e6f707172737475767778797a303132333435363738 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
