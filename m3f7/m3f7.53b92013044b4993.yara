
rule m3f7_53b92013044b4993
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.53b92013044b4993"
     cluster="m3f7.53b92013044b4993"
     cluster_size="81"
     filetype = "application/octet-stream"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['03400834fe421aafac18296fcaff86e0','058452a02bf98ffe288665da5b30849a','3547aba1aaaf2d7c52b6d7546fd7a228']"

   strings:
      $hex_string = { 44394241373030364644343533313338354534313942413941454236453046363238393237373241443834324443464136464330334537343333353130433543 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
