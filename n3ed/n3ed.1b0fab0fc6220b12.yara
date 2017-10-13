import "hash"

rule n3ed_1b0fab0fc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.1b0fab0fc6220b12"
     cluster="n3ed.1b0fab0fc6220b12"
     cluster_size="84 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['3b1f97344278afa7d0597aa330ed70c6', 'c98be0fbdc1e0972a5cad43f49d0c8f8', 'ba7ab9372ba8649adbdef073dbac61fc']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(296995,1059) == "529f9aec791a33f80d7be972c607e7b7"
}

