
rule k3e9_63b4b363d882d316
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.63b4b363d882d316"
     cluster="k3e9.63b4b363d882d316"
     cluster_size="293"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob virux"
     md5_hashes="['03f14a81598eb45e86651fa2f23d85c4','0628c7b437a656afe442ff7bd39e1671','269f081c8375567680cde8f391f8fde4']"

   strings:
      $hex_string = { 4dfc8b0989088a0b8848048345fc0446433bf77cb733dba1a08700018d34d8833eff754d85dbc646048175056af658eb0a8bc348f7d81bc083c0f550ff158410 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
