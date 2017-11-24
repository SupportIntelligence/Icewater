
rule p3e9_499abb49c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=p3e9.499abb49c8000b12"
     cluster="p3e9.499abb49c8000b12"
     cluster_size="103"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virlock ydutchkii nabucur"
     md5_hashes="['1a86aa94965150aa18d052a36b3ea294','1b9ee003d117e8cd4e01af41f7ebee5f','9c0502eb8e6aed4de527a820e7f36c70']"

   strings:
      $hex_string = { 3e02fbfbf97994a8f2ff0838f5ff325bfeff5376feff738efeff8ba3f8ffa4b4ecffb6bcdfffbcc6d4ffafd7caff8edcbeff4ad29cff0fbc79ff00a76bff0398 }

   condition:
      
      filesize > 4194304 and filesize < 16777216
      and $hex_string
}
