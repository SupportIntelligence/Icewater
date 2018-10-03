
rule k26df_691692ccced30932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k26df.691692ccced30932"
     cluster="k26df.691692ccced30932"
     cluster_size="9334"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="minicommander backdoor exploit"
     md5_hashes="['b2e704cefc0703d8a753bbc42fa47911284380d6','839054e4b527ff2f6c210ee4a4bdb1c771863938','59e46f50a9104e3574f144db920ab333171d4085']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k26df.691692ccced30932"

   strings:
      $hex_string = { 5777466a48396b34597633676c746a64693958326b70574151684a44656f4576666d736d3661326b4d75612b4a747a39456e5552313054412220262076624e65 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
