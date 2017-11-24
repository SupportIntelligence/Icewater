
rule k3e9_2b1a4a50d9bb0932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.2b1a4a50d9bb0932"
     cluster="k3e9.2b1a4a50d9bb0932"
     cluster_size="6"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ganelp autorun emailworm"
     md5_hashes="['07e24239ac4597b03fa325d34e01346a','26cf1f20627e7c68014e80df062127d4','fafb5d7bf5bca37af0e4fbca295d9aba']"

   strings:
      $hex_string = { 4f6730b3c6217f5b1cc2d5ee3f398f60e70da39c6188fbd72324f81e6236145cdb7a729d3896e2e0183a89562b0b4ef68c997b866cb4afeac045c7582c870725 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
