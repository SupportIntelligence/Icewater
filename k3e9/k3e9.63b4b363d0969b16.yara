
rule k3e9_63b4b363d0969b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.63b4b363d0969b16"
     cluster="k3e9.63b4b363d0969b16"
     cluster_size="16"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob classic"
     md5_hashes="['012f9557cb7667fbabfbc361ae790592','0a3508453d5c6e1d7043f8f0d73d2623','e0153ad27adefa7c02fafe5c3758db61']"

   strings:
      $hex_string = { 4dfc8b0989088a0b8848048345fc0446433bf77cb733dba1a08700018d34d8833eff754d85dbc646048175056af658eb0a8bc348f7d81bc083c0f550ff158410 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
