import "hash"

rule n3ee_1ab83b99c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ee.1ab83b99c2200b12"
     cluster="n3ee.1ab83b99c2200b12"
     cluster_size="11472 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="chem snarasite malicious"
     md5_hashes="['04f8060deec99f83d97a5ca1d7ac70a5', '038ed02770221c2902c5bb8f17c1cadb', '0453ef5567788ff79dcda474d39cd4f0']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(442368,1024) == "5d5bd7d8215887b4ffefa6784f8f65cb"
}

