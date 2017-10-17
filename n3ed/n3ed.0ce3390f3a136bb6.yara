import "hash"

rule n3ed_0ce3390f3a136bb6
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.0ce3390f3a136bb6"
     cluster="n3ed.0ce3390f3a136bb6"
     cluster_size="24 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['bf11ded2d39dcf994372607b05784a92', 'b64b72c176a3d03ccd23e78356ac42de', 'a27a24c011fd0cda3faabca93a5bcc3c']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(635392,1024) == "23ef210ac6a5becc04bd46daffa5e04f"
}

