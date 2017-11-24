
rule k3e9_45634226f9b34cb5
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.45634226f9b34cb5"
     cluster="k3e9.45634226f9b34cb5"
     cluster_size="2029"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob virux"
     md5_hashes="['001ae445233585835bdf5d663150cd4f','018ccb64b3019cd2b66cb351cc6ec14f','069bba9fba55be1844607249256a5dd4']"

   strings:
      $hex_string = { 1a33c983f87a0f94c14981e1f73ff9ff81c10e000780894dfceb1bc745fc57000780eb12575083c6085651ff1590600001395dfc74128b75088b063bc3740950 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
