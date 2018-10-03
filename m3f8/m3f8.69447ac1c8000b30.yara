
rule m3f8_69447ac1c8000b30
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f8.69447ac1c8000b30"
     cluster="m3f8.69447ac1c8000b30"
     cluster_size="9"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="androidos fakeinst fakeins"
     md5_hashes="['27429ef4a03f64164e9a484e77c0654afd6acb20','3dc09ab4a056119aab8ae411ae7fe55ebaf51949','b4ee7b6803c27d20e99428008286e253a9c46aac']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m3f8.69447ac1c8000b30"

   strings:
      $hex_string = { 77436e31757630353942734c4745333352616a4d4e764f2f6f327a6a4151744b5046414964335458775342476b56445a6d37784d707869724f3538486b6d6e68 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
