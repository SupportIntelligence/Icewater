
rule k3e9_13959a50cc227916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.13959a50cc227916"
     cluster="k3e9.13959a50cc227916"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="regrun ludbaruma rontokbro"
     md5_hashes="['05a63eaa1229eb113759e99a0ec2a362','76f7b6155e0b0a4f774b53d99d6b36c3','ea2bf21488514897cbe5beba1e77ef60']"

   strings:
      $hex_string = { dda34677e85b226a74aadb2bb4f5f04cf3f11ddad29e6518d54fafce2636c08b334b0824a00dcbc6acbc5061557a5256f6c27b33eb29ed9dd9c41a786366895a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
