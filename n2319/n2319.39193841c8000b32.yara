
rule n2319_39193841c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.39193841c8000b32"
     cluster="n2319.39193841c8000b32"
     cluster_size="13"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script faceliker clicker"
     md5_hashes="['d43c7c1e504f209a4d907c117f87c4167c245974','a20048352c6c127f4da18fabaa7abd4c53e2a764','674c5ecc2edab9db5e43466e67ee894f53142125']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.39193841c8000b32"

   strings:
      $hex_string = { 202077686572653a20646f63756d656e742e676574456c656d656e74427949642822666f6c6c6f776572732d696672616d652d636f6e7461696e657222292c0a }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
