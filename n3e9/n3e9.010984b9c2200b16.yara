import "hash"

rule n3e9_010984b9c2200b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.010984b9c2200b16"
     cluster="n3e9.010984b9c2200b16"
     cluster_size="152 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     family="syncopate unwanted malicious"
     md5_hashes="['45af78ab60ad3b082ec2ed421261de8c', '921d124d75a5bc18badb032942322dec', 'b0b6f97c469ed28092dc7cb04b0a6fcc']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(293888,1024) == "aa895101d05aeb1c4f348a7199cae7ab"
}

