import "hash"

rule n3e9_1b1dbec9c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.1b1dbec9c4000b12"
     cluster="n3e9.1b1dbec9c4000b12"
     cluster_size="20 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="jadtre otwycal wapomi"
     md5_hashes="['84512d98ea340440219bb543ed3cb042', '95f5acab508dd0e8764f8cd9019d7b58', 'dd1875382d88f411d29621a83fb40608']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(57344,1024) == "17bb2f77974ec7dfe7028de9f705c059"
}

