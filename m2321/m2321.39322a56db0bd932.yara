
rule m2321_39322a56db0bd932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.39322a56db0bd932"
     cluster="m2321.39322a56db0bd932"
     cluster_size="29"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ngrbot ainslot ruskill"
     md5_hashes="['0216195c3d43972b385924e7aa5f5dd7','023f36f0677306ba27e4ca73dd22594f','ae82d0434efafd3ca93e6ad3e432280a']"

   strings:
      $hex_string = { 65f27a8d3984fb1c697199913cd5d1952adb80226dfbdebfc5d0634b7e103831f00b1f818c83874aca7689ede819b170a314c473cc3a032bb5f76286af30e0aa }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
