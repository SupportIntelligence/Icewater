
rule m3e9_693f84a6ded31912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.693f84a6ded31912"
     cluster="m3e9.693f84a6ded31912"
     cluster_size="207"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="otwycal wapomi vjadtre"
     md5_hashes="['02bc4ea1e884df37088e8d6718c16eb0','0c81090fa62dd0862f3f46247a5cb1d2','54ae65efe7b3fce9400c65ba179aa5c4']"

   strings:
      $hex_string = { 1e55b037fde2de87ebab4128ffc578b61533beef6262be8a0ceea4a0ad660e963d385a28827da03547bf4a2afafadedc8f200a2e32669c640f7b4691f5d14b55 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
