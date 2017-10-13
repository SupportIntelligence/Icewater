import "hash"

rule m3e7_231c3949c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e7.231c3949c0000b32"
     cluster="m3e7.231c3949c0000b32"
     cluster_size="25 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="allaple rahack backdoor"
     md5_hashes="['a5510a7753849bd4279810f3a17eac75', 'fa6625fe5dcde685dd6d4a8a005d2f54', '6ec2255e8fa4bd972f6ff7dc2f284959']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(62090,1058) == "2cc91028f6f559f9c633c41bba0674cd"
}

