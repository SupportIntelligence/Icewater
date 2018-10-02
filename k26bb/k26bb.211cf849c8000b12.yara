
rule k26bb_211cf849c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k26bb.211cf849c8000b12"
     cluster="k26bb.211cf849c8000b12"
     cluster_size="810"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="backdoor darkkomet malicious"
     md5_hashes="['6c6c8ba265b8a0dfff8fcaffafed441e36b026fe','0a6d2ba1a4c33e1c0c8506a5ae1fa3d3da624857','5ea2e7ceb178e323fb1597594b26067863e92da0']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k26bb.211cf849c8000b12"

   strings:
      $hex_string = { 140bd3e03b55f4731e8d7455a48bff0fb73e2bc785c07e0c424183c60203c03b55f472eb8b75dcb8010000008bf8d3e7017de8897dd0394508750d817de8b005 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
