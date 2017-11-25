
rule i3f7_139da94a101d6b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i3f7.139da94a101d6b16"
     cluster="i3f7.139da94a101d6b16"
     cluster_size="4"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="iframe html script"
     md5_hashes="['9572dd6235f98e881a3f0749f7b60d29','9daccee87021d091ae1545793c495150','cc33617c07db7a0075403c04eb5c8f3e']"

   strings:
      $hex_string = { 682e72616e646f6d28292b0d0a222720616c743d2727207469746c653d274c697665496e7465726e65743a20cfeeeae0e7e0edee20f7e8f1ebee20eff0eef1ec }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
