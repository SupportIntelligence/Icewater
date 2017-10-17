import "hash"

rule m3e9_7856426ac4aac393
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.7856426ac4aac393"
     cluster="m3e9.7856426ac4aac393"
     cluster_size="16 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="diple chinky vobfus"
     md5_hashes="['c6ea464eaaa9bd0e458c09bf7928d8aa', '628ec2825285d7526d6a636d68edde6c', '42e97f024737d61bcdbc26d8ef6b3314']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(149504,1024) == "3988087b126b34350adb1cce0ee28c3f"
}

