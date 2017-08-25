import "hash"

rule m3e9_118696c9cc000932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.118696c9cc000932"
     cluster="m3e9.118696c9cc000932"
     cluster_size="20842 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['03ae7324d6d02ca0410fd8d0655d4d7e', '05454a1dee7107b68ab9337384de030c', '05f22356b858331e806ad026572ba1de']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(36864,1024) == "be36e7d837001e86681445cdf3c7723f"
}

