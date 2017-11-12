
rule k3e9_56a723b396c31112
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.56a723b396c31112"
     cluster="k3e9.56a723b396c31112"
     cluster_size="811"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="unruy cycler clicker"
     md5_hashes="['0013fceed930e80b621d5d62064ce64c','002e7f6710c6465ef249524e1de2803e','0e425cafe1e59620674f586b7b0fede4']"

   strings:
      $hex_string = { 002b28aaa55dad017c97b20e21e93e24f08493ef6fa8834b18b87552ac3d5b7fcb2ee413c2f2a44e659cf69b81d788ab024a7905851f64b41ad317ae0fc0a3c9 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
