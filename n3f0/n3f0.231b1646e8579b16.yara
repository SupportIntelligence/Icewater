import "hash"

rule n3f0_231b1646e8579b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f0.231b1646e8579b16"
     cluster="n3f0.231b1646e8579b16"
     cluster_size="3 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="mira ccpk malicious"
     md5_hashes="['c1622fc99686bd527b0da3793419a724', '38b7fb103f117acee17314ae2a7a0061', 'c1622fc99686bd527b0da3793419a724']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(214016,1024) == "883e44562af9c167d628e72736977547"
}

