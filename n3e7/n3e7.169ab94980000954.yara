import "hash"

rule n3e7_169ab94980000954
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e7.169ab94980000954"
     cluster="n3e7.169ab94980000954"
     cluster_size="237 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="allaple rahack virut"
     md5_hashes="['a4ab1652ccb6b76be26ff66721127369', 'c7114ebc15150007a729e699e1c6ae87', 'a2c2bd2d2a21b211fbbb85ee0fe85821']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(162784,1028) == "4f535038e929bf7b3ba8d207de4f234e"
}

