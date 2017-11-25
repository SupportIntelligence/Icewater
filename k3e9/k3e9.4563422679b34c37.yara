
rule k3e9_4563422679b34c37
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.4563422679b34c37"
     cluster="k3e9.4563422679b34c37"
     cluster_size="9"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob virux"
     md5_hashes="['3906f6c9b4d29de68f9d4c0c72b4ee7c','a0e480ff2137d12d026cd96d976af86f','cea261b8f55614c170f9aed2f30657d7']"

   strings:
      $hex_string = { 1a33c983f87a0f94c14981e1f73ff9ff81c10e000780894dfceb1bc745fc57000780eb12575083c6085651ff1590600001395dfc74128b75088b063bc3740950 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
