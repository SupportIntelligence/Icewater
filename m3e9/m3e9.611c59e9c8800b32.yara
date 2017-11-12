
rule m3e9_611c59e9c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.611c59e9c8800b32"
     cluster="m3e9.611c59e9c8800b32"
     cluster_size="416"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob malicious"
     md5_hashes="['02d0a480170a3688fe7e2fda48abf236','0367edbb4e9bb01b7e3181afcc1efe17','09d2ac35c090106ac11da35969e84b2f']"

   strings:
      $hex_string = { 3bf37d10391da8e60001740b5668f0290001ebbe33db435e8d45f850ff15f41100015f8bc35bc9c20800558bec83ec1853568b750c5733db33c066895df08d7d }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
