
rule n2706_4a549899ee210b14
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2706.4a549899ee210b14"
     cluster="n2706.4a549899ee210b14"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="browsefox ursu injector"
     md5_hashes="['2dd345a33319c567e0321543bb6bcb14e5092570','54b1f1234c587c48a3fe907e6e7595a60e65804e','cf2171bbfeea875803c3105c5daa1df879f96188']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2706.4a549899ee210b14"

   strings:
      $hex_string = { 3737393162646131613330383934366563323534663000457175616c73006f626a0066756e6374696f6e006100620047657448617368436f6465006f705f4571 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
