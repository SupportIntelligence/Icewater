
rule n3ed_54921cc1cc000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.54921cc1cc000b32"
     cluster="n3ed.54921cc1cc000b32"
     cluster_size="79"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit nimnul bmnup"
     md5_hashes="['04fd751bdba708b2e54134f0af2dd6c5','09466a08c6c21a5936e21d4a33625046','37a5a4454730c7d6f06d001292aba29e']"

   strings:
      $hex_string = { 1b5239548a7076632495825725663f6987910755f36daf7e22883362f07eb5752883c178cc969e8f4861f774cd8b646b3a52508d216b6a807184f1560653ce4e }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
