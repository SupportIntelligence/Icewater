
rule m2321_291997a9c2000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.291997a9c2000b12"
     cluster="m2321.291997a9c2000b12"
     cluster_size="15"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut midie shodi"
     md5_hashes="['022d3b81fd28149ae2f4751833ae60c1','102bc845893d2e119eaeccc6f4af84b3','f0d63d4c637d66c2401e712e466ff4a3']"

   strings:
      $hex_string = { 4df9fe560a414c942dbaac3bccbd8b21f101ab4b6cb25eb1324982d210c9a219e0ff1fe85c04ece18d0cd218b5cba95b23641631dc1533c35563092c608a02d7 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
