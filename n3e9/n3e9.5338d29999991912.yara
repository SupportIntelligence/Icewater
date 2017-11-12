import "hash"

rule n3e9_5338d29999991912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.5338d29999991912"
     cluster="n3e9.5338d29999991912"
     cluster_size="536 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['a2b22c88330f20093c2c3f528a157079', 'b1611dc1f40862ef5fe349ee277447e8', 'ca44cab1f1d6d0917ed72970a1574526']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(503808,1024) == "3fe14b266c4bcc97c5475b777c222024"
}

