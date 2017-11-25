
rule j3f7_6934ea49c0001932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f7.6934ea49c0001932"
     cluster="j3f7.6934ea49c0001932"
     cluster_size="12"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="iframe html iframeref"
     md5_hashes="['03f4bb0d41ab8540488d901ffb370fac','1e54ee809b4ffa73f2b727a7b44ac475','c70958f5da68a7b167eb918d3b9638da']"

   strings:
      $hex_string = { 3435207372633d687474703a2f2f6e6d736261736562616c6c2e636f6d2f706f73742e7068703f69643d3636363038383e3c2f696672616d653e3c2f626f6479 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
