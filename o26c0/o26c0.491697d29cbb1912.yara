
rule o26c0_491697d29cbb1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26c0.491697d29cbb1912"
     cluster="o26c0.491697d29cbb1912"
     cluster_size="23"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="strictor malicious filerepmalware"
     md5_hashes="['6d7d6c2c08c409b3121d54cc28c683f9601f26c6','879b114fd8a961c7ace007e1771d4f48183fc99f','9b95d8dd2399cc0e8dec1740e5d74f3ad39de8c6']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26c0.491697d29cbb1912"

   strings:
      $hex_string = { c969e6ff159947e3396a4fa3b92f8bd5f12b48191c241a6d54882d86b20e114c87f20dda643c51509eeaec9f8a088ff3e9cd5634003bdb53b62a4d01333d8365 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
