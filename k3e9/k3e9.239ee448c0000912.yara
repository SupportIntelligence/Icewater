
rule k3e9_239ee448c0000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.239ee448c0000912"
     cluster="k3e9.239ee448c0000912"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family=""
     md5_hashes="['19d185e524b7794211b466f065c8d134','2e947af127fc7fe3ceae1a208cbd37d6','66c420f6263e40467f21149d4ed68c0c']"

   strings:
      $hex_string = { 3dffe488c242373141d03adac6b791940a7b3f90fb2ca2e6c4686362542b47697f4fc7859b6c1ecbc3b656bd307c0787c9462ff940e965e9764e8c05f0e5640b }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
